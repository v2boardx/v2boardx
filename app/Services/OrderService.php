<?php

namespace App\Services;

use App\Jobs\OrderHandleJob;
use App\Models\Order;
use App\Models\Plan;
use App\Models\User;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class OrderService
{
    CONST STR_TO_TIME = [
        'month_price' => 1,
        'quarter_price' => 3,
        'half_year_price' => 6,
        'year_price' => 12,
        'two_year_price' => 24,
        'three_year_price' => 36
    ];
    public $order;
    public $user;

    public function __construct(Order $order)
    {
        $this->order = $order;
    }

    public function open()
    {
        $order = $this->order;
        $this->user = User::find($order->user_id);
        $plan = Plan::find($order->plan_id);

        if ($order->refund_amount) {
            $this->user->balance = $this->user->balance + $order->refund_amount;
        }
        DB::beginTransaction();
        if ($order->surplus_order_ids) {
            try {
                Order::whereIn('id', $order->surplus_order_ids)->update([
                    'status' => 4
                ]);
            } catch (\Exception $e) {
                DB::rollback();
                abort(500, '开通失败');
            }
        }
        switch ((string)$order->period) {
            case 'onetime_price':
                $this->buyByOneTime($plan);
                break;
            case 'reset_price':
                $this->buyByResetTraffic();
                break;
            default:
                $this->buyByPeriod($order, $plan);
        }

        switch ((int)$order->type) {
            case 1:
                $this->openEvent(config('v2board.new_order_event_id', 0));
                break;
            case 2:
                $this->openEvent(config('v2board.renew_order_event_id', 0));
                break;
            case 3:
                $this->openEvent(config('v2board.change_order_event_id', 0));
                break;
        }

        $this->setSpeedLimit($plan->speed_limit);

        if (!$this->user->save()) {
            DB::rollBack();
            abort(500, '开通失败');
        }
        $order->status = 3;
        if (!$order->save()) {
            DB::rollBack();
            abort(500, '开通失败');
        }

        DB::commit();
    }


    public function setOrderType(User $user)
    {
        $order = $this->order;
        if ($order->period === 'reset_price') {
            $order->type = 4;
        } else if ($user->plan_id !== NULL && $order->plan_id !== $user->plan_id && ($user->expired_at > time() || $user->expired_at === NULL)) {
            if (!(int)config('v2board.plan_change_enable', 1)) abort(500, '目前不允许更改订阅，请联系客服或提交工单操作');
            $order->type = 3;
            $this->getSurplusValue($user, $order);
            if ($order->surplus_amount >= $order->total_amount) {
                $order->refund_amount = $order->surplus_amount - $order->total_amount;
                $order->total_amount = 0;
            } else {
                $order->total_amount = $order->total_amount - $order->surplus_amount;
            }
        } else if ($user->expired_at > time() && $order->plan_id == $user->plan_id) { // 用户订阅未过期且购买订阅与当前订阅相同 === 续费
            $order->type = 2;
        } else { // 新购
            $order->type = 1;
        }
    }

    public function setVipDiscount(User $user)
    {
        $order = $this->order;
        if ($user->discount) {
            $order->discount_amount = $order->discount_amount + ($order->total_amount * ($user->discount / 100));
        }
        $order->total_amount = $order->total_amount - $order->discount_amount;
    }

    public function setInvite(User $user):void
    {
        $order = $this->order;
        if ($user->invite_user_id && ($order->total_amount <= 0)) return;
        $order->invite_user_id = $user->invite_user_id;
        $inviter = User::find($user->invite_user_id);
        if (!$inviter) return;
        $isCommission = false;
        switch ((int)$inviter->commission_type) {
            case 0:
                $commissionFirstTime = (int)config('v2board.commission_first_time_enable', 1);
                $isCommission = (!$commissionFirstTime || ($commissionFirstTime && !$this->haveValidOrder($user)));
                break;
            case 1:
                $isCommission = true;
                break;
            case 2:
                $isCommission = !$this->haveValidOrder($user);
                break;
        }

        if (!$isCommission) return;
        if ($inviter && $inviter->commission_rate) {
            $order->commission_balance = $order->total_amount * ($inviter->commission_rate / 100);
        } else {
            $order->commission_balance = $order->total_amount * (config('v2board.invite_commission', 10) / 100);
        }
    }

    private function haveValidOrder(User $user)
    {
        return Order::where('user_id', $user->id)
            ->whereNotIn('status', [0, 2])
            ->first();
    }

    private function getSurplusValue(User $user, Order $order)
    {
        $plan = Plan::find($user->plan_id);
        if (!$plan) return;
        // 如果套餐是按流量卖的，没有过期时间，则直接按照剩余流量残值计算
        if ($user->expired_at === NULL) {
            $this->getSurplusValueByTransfer($user, $order, $plan);
            return;
        }

        // 如果套餐是按周期卖的，先计算剩余时间残值，然后加上剩余流量残值
        $this->getSurplusValueByTime($user, $order, $plan);
        $this->getSurplusValueByTransfer($user, $order, $plan);
    }

    private function getSurplusValueByTime(User $user, Order $order, Plan $plan)
    {
        if (!$plan['daily_unit_price']) return;

        $timeLeftDays = ($user['expired_at'] - time()) / 86400;

        if (!$timeLeftDays) return;
        // 如果套餐剩余时长小于 30 天，则不计算时间残值
        if ($timeLeftDays < 30) return;

        // 如果套餐剩余时长大于 30 天，则只计算整月，剩余部分是按剩余流量残值计算
        $realTimeLeftDays = intval($timeLeftDays / 30) * 30;

        $dailyUnitPrice = $plan['daily_unit_price'] / 100;
        $order->surplus_amount = $order->surplus_amount + ($realTimeLeftDays * $dailyUnitPrice);
    }

    private function getSurplusValueByTransfer(User $user, Order $order, Plan $plan)
    {
        if (!$plan['transfer_unit_price']) return;
        $transferLeft = ($user['transfer_enable'] - ($user['u'] + $user['d'])) / 1073741824;
        if (!$transferLeft) return;
        // 如果套餐剩余流量为 0 或者负数，则不计算剩余流量残值
        if ($transferLeft <= 0) return;

        $transferUnitPrice = $plan['transfer_unit_price'] / 100;
        $order->surplus_amount = $order->surplus_amount + ($transferLeft * $transferUnitPrice);
    }

    public function paid(string $callbackNo)
    {
        $order = $this->order;
        if ($order->status !== 0) return true;
        $order->status = 1;
        $order->paid_at = time();
        $order->callback_no = $callbackNo;
        if (!$order->save()) return false;
        try {
            OrderHandleJob::dispatchNow($order->trade_no);
        } catch (\Exception $e) {
            return false;
        }
        return true;
    }

    public function cancel():bool
    {
        $order = $this->order;
        DB::beginTransaction();
        $order->status = 2;
        if (!$order->save()) {
            DB::rollBack();
            return false;
        }
        if ($order->balance_amount) {
            $userService = new UserService();
            if (!$userService->addBalance($order->user_id, $order->balance_amount)) {
                DB::rollBack();
                return false;
            }
        }
        DB::commit();
        return true;
    }

    private function setSpeedLimit($speedLimit)
    {
        $this->user->speed_limit = $speedLimit;
    }

    private function buyByResetTraffic()
    {
        $this->user->u = 0;
        $this->user->d = 0;
    }

    private function buyByPeriod(Order $order, Plan $plan)
    {
        // change plan process
        if ((int)$order->type === 3) {
            $this->user->expired_at = time();
        }
        $this->user->transfer_enable = $plan->transfer_enable * 1073741824;
        // 从一次性转换到循环
        if ($this->user->expired_at === NULL) $this->buyByResetTraffic();
        // 新购
        if ($order->type === 1) $this->buyByResetTraffic();
        $this->user->plan_id = $plan->id;
        $this->user->group_id = $plan->group_id;
        $this->user->expired_at = $this->getTime($order->period, $this->user->expired_at);
    }

    private function buyByOneTime(Plan $plan)
    {
        $this->buyByResetTraffic();
        $this->user->transfer_enable = $plan->transfer_enable * 1073741824;
        $this->user->plan_id = $plan->id;
        $this->user->group_id = $plan->group_id;
        $this->user->expired_at = NULL;
    }

    private function getTime($str, $timestamp)
    {
        if ($timestamp < time()) {
            $timestamp = time();
        }
        switch ($str) {
            case 'month_price':
                return strtotime('+1 month', $timestamp);
            case 'quarter_price':
                return strtotime('+3 month', $timestamp);
            case 'half_year_price':
                return strtotime('+6 month', $timestamp);
            case 'year_price':
                return strtotime('+12 month', $timestamp);
            case 'two_year_price':
                return strtotime('+24 month', $timestamp);
            case 'three_year_price':
                return strtotime('+36 month', $timestamp);
        }
    }

    private function openEvent($eventId)
    {
        switch ((int) $eventId) {
            case 0:
                break;
            case 1:
                $this->buyByResetTraffic();
                break;
        }
    }
}
